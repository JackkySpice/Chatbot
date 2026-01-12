.class public Landroidx/appcompat/view/menu/gw;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/lifecycle/e;
.implements Landroidx/appcompat/view/menu/nr0;
.implements Landroidx/appcompat/view/menu/x51;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/ev;

.field public final b:Landroidx/appcompat/view/menu/w51;

.field public final c:Ljava/lang/Runnable;

.field public d:Landroidx/lifecycle/i;

.field public e:Landroidx/appcompat/view/menu/mr0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ev;Landroidx/appcompat/view/menu/w51;Ljava/lang/Runnable;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/appcompat/view/menu/gw;->d:Landroidx/lifecycle/i;

    iput-object v0, p0, Landroidx/appcompat/view/menu/gw;->e:Landroidx/appcompat/view/menu/mr0;

    iput-object p1, p0, Landroidx/appcompat/view/menu/gw;->a:Landroidx/appcompat/view/menu/ev;

    iput-object p2, p0, Landroidx/appcompat/view/menu/gw;->b:Landroidx/appcompat/view/menu/w51;

    iput-object p3, p0, Landroidx/appcompat/view/menu/gw;->c:Ljava/lang/Runnable;

    return-void
.end method


# virtual methods
.method public a(Landroidx/lifecycle/f$a;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->d:Landroidx/lifecycle/i;

    invoke-virtual {v0, p1}, Landroidx/lifecycle/i;->h(Landroidx/lifecycle/f$a;)V

    return-void
.end method

.method public b()Landroidx/appcompat/view/menu/fi;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->a:Landroidx/appcompat/view/menu/ev;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->R0()Landroid/content/Context;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    :goto_0
    instance-of v1, v0, Landroid/content/ContextWrapper;

    if-eqz v1, :cond_1

    instance-of v1, v0, Landroid/app/Application;

    if-eqz v1, :cond_0

    check-cast v0, Landroid/app/Application;

    goto :goto_1

    :cond_0
    check-cast v0, Landroid/content/ContextWrapper;

    invoke-virtual {v0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_1
    new-instance v1, Landroidx/appcompat/view/menu/fe0;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/fe0;-><init>()V

    if-eqz v0, :cond_2

    sget-object v2, Landroidx/lifecycle/r$a;->e:Landroidx/appcompat/view/menu/fi$b;

    invoke-virtual {v1, v2, v0}, Landroidx/appcompat/view/menu/fe0;->b(Landroidx/appcompat/view/menu/fi$b;Ljava/lang/Object;)V

    :cond_2
    sget-object v0, Landroidx/lifecycle/p;->a:Landroidx/appcompat/view/menu/fi$b;

    iget-object v2, p0, Landroidx/appcompat/view/menu/gw;->a:Landroidx/appcompat/view/menu/ev;

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/fe0;->b(Landroidx/appcompat/view/menu/fi$b;Ljava/lang/Object;)V

    sget-object v0, Landroidx/lifecycle/p;->b:Landroidx/appcompat/view/menu/fi$b;

    invoke-virtual {v1, v0, p0}, Landroidx/appcompat/view/menu/fe0;->b(Landroidx/appcompat/view/menu/fi$b;Ljava/lang/Object;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->a:Landroidx/appcompat/view/menu/ev;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ev;->o()Landroid/os/Bundle;

    move-result-object v0

    if-eqz v0, :cond_3

    sget-object v0, Landroidx/lifecycle/p;->c:Landroidx/appcompat/view/menu/fi$b;

    iget-object v2, p0, Landroidx/appcompat/view/menu/gw;->a:Landroidx/appcompat/view/menu/ev;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/ev;->o()Landroid/os/Bundle;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/fe0;->b(Landroidx/appcompat/view/menu/fi$b;Ljava/lang/Object;)V

    :cond_3
    return-object v1
.end method

.method public c()Landroidx/appcompat/view/menu/w51;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gw;->d()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->b:Landroidx/appcompat/view/menu/w51;

    return-object v0
.end method

.method public d()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->d:Landroidx/lifecycle/i;

    if-nez v0, :cond_0

    new-instance v0, Landroidx/lifecycle/i;

    invoke-direct {v0, p0}, Landroidx/lifecycle/i;-><init>(Landroidx/appcompat/view/menu/x80;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/gw;->d:Landroidx/lifecycle/i;

    invoke-static {p0}, Landroidx/appcompat/view/menu/mr0;->a(Landroidx/appcompat/view/menu/nr0;)Landroidx/appcompat/view/menu/mr0;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/gw;->e:Landroidx/appcompat/view/menu/mr0;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/mr0;->c()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->c:Ljava/lang/Runnable;

    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    :cond_0
    return-void
.end method

.method public e()Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->d:Landroidx/lifecycle/i;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public f(Landroid/os/Bundle;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->e:Landroidx/appcompat/view/menu/mr0;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/mr0;->d(Landroid/os/Bundle;)V

    return-void
.end method

.method public g(Landroid/os/Bundle;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->e:Landroidx/appcompat/view/menu/mr0;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/mr0;->e(Landroid/os/Bundle;)V

    return-void
.end method

.method public h()Landroidx/lifecycle/f;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gw;->d()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->d:Landroidx/lifecycle/i;

    return-object v0
.end method

.method public l()Landroidx/appcompat/view/menu/lr0;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gw;->d()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/gw;->e:Landroidx/appcompat/view/menu/mr0;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/mr0;->b()Landroidx/appcompat/view/menu/lr0;

    move-result-object v0

    return-object v0
.end method
