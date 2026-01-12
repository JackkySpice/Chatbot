.class public Landroidx/appcompat/view/menu/f71$a;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/f71;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/jd0;-><init>()V

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/g71;->b:Landroidx/appcompat/view/menu/co0$b;

    const/4 v1, 0x0

    aget-object v1, p3, v1

    const-class v2, Lcom/snake/helper/ProxyVpnService;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Landroidx/appcompat/view/menu/g71;->d:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/f71$a;->f(Ljava/util/List;)V

    sget-object v0, Landroidx/appcompat/view/menu/g71;->c:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/f71$a;->f(Ljava/util/List;)V

    invoke-virtual {p2, p1, p3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final f(Ljava/util/List;)V
    .locals 1

    if-nez p1, :cond_0

    return-void

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->E2()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_1
    return-void
.end method
