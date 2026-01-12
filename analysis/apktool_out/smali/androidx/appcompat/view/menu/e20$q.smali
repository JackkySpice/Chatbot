.class public Landroidx/appcompat/view/menu/e20$q;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/e20;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "q"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/jd0;-><init>()V

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    const/4 v0, 0x0

    aget-object v0, p3, v0

    check-cast v0, Ljava/lang/String;

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->j()Z

    move-result v1

    const/4 v2, 0x1

    if-eqz v1, :cond_0

    aget-object v1, p3, v2

    check-cast v1, Ljava/lang/Long;

    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    move-result-wide v1

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->u()Landroidx/appcompat/view/menu/mv0;

    move-result-object v3

    invoke-static {v1, v2}, Ljava/lang/Math;->toIntExact(J)I

    move-result v1

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v2

    invoke-virtual {v3, v0, v1, v2}, Landroidx/appcompat/view/menu/mv0;->y(Ljava/lang/String;II)Landroid/content/pm/ProviderInfo;

    move-result-object v0

    goto :goto_0

    :cond_0
    aget-object v1, p3, v2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->u()Landroidx/appcompat/view/menu/mv0;

    move-result-object v2

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v3

    invoke-virtual {v2, v0, v1, v3}, Landroidx/appcompat/view/menu/mv0;->y(Ljava/lang/String;II)Landroid/content/pm/ProviderInfo;

    move-result-object v0

    :goto_0
    if-nez v0, :cond_1

    invoke-virtual {p2, p1, p3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    return-object v0
.end method
