.class public Landroidx/appcompat/view/menu/e20$m;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/e20;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "m"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/jd0;-><init>()V

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    const/4 v0, 0x0

    aget-object v0, p3, v0

    check-cast v0, Ljava/lang/String;

    invoke-static {}, Landroidx/appcompat/view/menu/w6;->w2()Landroidx/appcompat/view/menu/w6;

    move-result-object v1

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/w6;->z2(Ljava/lang/String;)Landroidx/appcompat/view/menu/x6;

    move-result-object v0

    if-eqz v0, :cond_2

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iget-object p2, v0, Landroidx/appcompat/view/menu/x6;->m:Landroidx/appcompat/view/menu/t6;

    iget-object p2, p2, Landroidx/appcompat/view/menu/t6;->B:Ljava/util/ArrayList;

    if-eqz p2, :cond_0

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    :cond_0
    iget-object p2, v0, Landroidx/appcompat/view/menu/x6;->m:Landroidx/appcompat/view/menu/t6;

    iget-object p2, p2, Landroidx/appcompat/view/menu/t6;->C:Ljava/util/ArrayList;

    if-eqz p2, :cond_1

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    :cond_1
    invoke-static {p1}, Landroidx/appcompat/view/menu/jh0;->a(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p2, p1, p3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
