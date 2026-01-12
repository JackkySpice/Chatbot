.class public Landroidx/appcompat/view/menu/e20$e;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/e20;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "e"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/jd0;-><init>()V

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->j()Z

    move-result p1

    const/4 p2, 0x0

    if-eqz p1, :cond_0

    aget-object p1, p3, p2

    check-cast p1, Ljava/lang/Long;

    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide p1

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->u()Landroidx/appcompat/view/menu/mv0;

    move-result-object p3

    invoke-static {p1, p2}, Ljava/lang/Math;->toIntExact(J)I

    move-result p1

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result p2

    invoke-virtual {p3, p1, p2}, Landroidx/appcompat/view/menu/mv0;->j(II)Ljava/util/List;

    move-result-object p1

    goto :goto_0

    :cond_0
    aget-object p1, p3, p2

    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->u()Landroidx/appcompat/view/menu/mv0;

    move-result-object p2

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result p3

    invoke-virtual {p2, p1, p3}, Landroidx/appcompat/view/menu/mv0;->j(II)Ljava/util/List;

    move-result-object p1

    :goto_0
    invoke-static {p1}, Landroidx/appcompat/view/menu/jh0;->a(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
