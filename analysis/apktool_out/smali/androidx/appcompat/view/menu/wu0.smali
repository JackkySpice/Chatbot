.class public Landroidx/appcompat/view/menu/wu0;
.super Landroidx/appcompat/view/menu/gv0;
.source "SourceFile"


# static fields
.field public static final d:Landroidx/appcompat/view/menu/wu0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/wu0;

    const-class v1, Landroidx/appcompat/view/menu/h00;

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/wu0;-><init>(Ljava/lang/Class;)V

    sput-object v0, Landroidx/appcompat/view/menu/wu0;->d:Landroidx/appcompat/view/menu/wu0;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;)V
    .locals 0

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/gv0;-><init>(Ljava/lang/Class;)V

    return-void
.end method

.method public static o()Landroidx/appcompat/view/menu/wu0;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/wu0;->d:Landroidx/appcompat/view/menu/wu0;

    return-object v0
.end method


# virtual methods
.method public A(Landroid/accounts/Account;)Ljava/lang/String;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, v1}, Landroidx/appcompat/view/menu/h00;->N1(Landroid/accounts/Account;I)Ljava/lang/String;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public B(Landroid/accounts/Account;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->r(Landroid/accounts/Account;Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public C(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->X0(Ljava/lang/String;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public D(Landroid/accounts/Account;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->l2(Landroid/accounts/Account;Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public E([Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->w1([Ljava/lang/String;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public F(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Z)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->a1(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;ZI)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public G(Landroid/accounts/Account;)Z
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, v1}, Landroidx/appcompat/view/menu/h00;->i1(Landroid/accounts/Account;I)Z

    move-result p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return p1
.end method

.method public H(Landroid/accounts/Account;Ljava/lang/String;I)Z
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->m0(Landroid/accounts/Account;Ljava/lang/String;II)Z

    move-result p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return p1
.end method

.method public I(Landroid/accounts/Account;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->G(Landroid/accounts/Account;Ljava/lang/String;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public J(Landroid/accounts/Account;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->y1(Landroid/accounts/Account;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public K(Landroid/accounts/Account;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->c1(Landroid/accounts/Account;Ljava/lang/String;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public L([Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->Z([Ljava/lang/String;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public M(Landroid/accounts/Account;Ljava/lang/String;IZ)V
    .locals 1

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-interface {v0, p1, p2, p3, p4}, Landroidx/appcompat/view/menu/h00;->r2(Landroid/accounts/Account;Ljava/lang/String;IZ)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public N(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Ljava/lang/String;ZLandroid/os/Bundle;)V
    .locals 8

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v7

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    move-object v6, p5

    invoke-interface/range {v1 .. v7}, Landroidx/appcompat/view/menu/h00;->f1(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Ljava/lang/String;ZLandroid/os/Bundle;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public d()Ljava/lang/String;
    .locals 1

    const-string v0, "account_manager"

    return-object v0
.end method

.method public f(Landroid/accounts/Account;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, v1}, Landroidx/appcompat/view/menu/h00;->p0(Landroid/accounts/Account;I)Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public g(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ZLandroid/os/Bundle;)V
    .locals 9

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v8

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move v6, p5

    move-object v7, p6

    invoke-interface/range {v1 .. v8}, Landroidx/appcompat/view/menu/h00;->M0(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ZLandroid/os/Bundle;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public h(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ZLandroid/os/Bundle;)V
    .locals 9

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v8

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move v6, p5

    move-object v7, p6

    invoke-interface/range {v1 .. v8}, Landroidx/appcompat/view/menu/h00;->K1(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ZLandroid/os/Bundle;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public i(Landroid/accounts/Account;Ljava/lang/String;Landroid/os/Bundle;)Z
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->R0(Landroid/accounts/Account;Ljava/lang/String;Landroid/os/Bundle;I)Z

    move-result p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return p1
.end method

.method public j(Landroid/accounts/Account;Ljava/lang/String;Landroid/os/Bundle;Ljava/util/Map;)Z
    .locals 7

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v6

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    invoke-interface/range {v1 .. v6}, Landroidx/appcompat/view/menu/h00;->s1(Landroid/accounts/Account;Ljava/lang/String;Landroid/os/Bundle;Ljava/util/Map;I)Z

    move-result p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return p1
.end method

.method public k(Landroid/accounts/Account;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, v1}, Landroidx/appcompat/view/menu/h00;->J1(Landroid/accounts/Account;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public l(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Landroid/os/Bundle;Z)V
    .locals 7

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v6

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-interface/range {v1 .. v6}, Landroidx/appcompat/view/menu/h00;->Y(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Landroid/os/Bundle;ZI)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public m(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;II)V
    .locals 1

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-interface {v0, p1, p2, p3, p4}, Landroidx/appcompat/view/menu/h00;->d2(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;II)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public n(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Z)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->T0(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;ZI)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public p(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;[Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->M1(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;[Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public q(Landroid/accounts/Account;Ljava/lang/String;)I
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->E0(Landroid/accounts/Account;Ljava/lang/String;I)I

    move-result p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x3

    return p1
.end method

.method public r(Ljava/lang/String;Ljava/lang/String;)Ljava/util/Map;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->f0(Ljava/lang/String;Ljava/lang/String;I)Ljava/util/Map;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public s(Ljava/lang/String;)[Landroid/accounts/Account;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, v1}, Landroidx/appcompat/view/menu/h00;->I1(Ljava/lang/String;I)[Landroid/accounts/Account;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public t(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;[Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->A1(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;[Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public u(Ljava/lang/String;Ljava/lang/String;)[Landroid/accounts/Account;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->d1(Ljava/lang/String;Ljava/lang/String;I)[Landroid/accounts/Account;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public v(Ljava/lang/String;I)[Landroid/accounts/Account;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, v1}, Landroidx/appcompat/view/menu/h00;->S1(Ljava/lang/String;II)[Landroid/accounts/Account;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method

.method public w(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Ljava/lang/String;ZZLandroid/os/Bundle;)V
    .locals 9

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v8

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    move v6, p5

    move-object v7, p6

    invoke-interface/range {v1 .. v8}, Landroidx/appcompat/view/menu/h00;->k1(Landroid/accounts/IAccountManagerResponse;Landroid/accounts/Account;Ljava/lang/String;ZZLandroid/os/Bundle;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public x(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, p2, p3, v1}, Landroidx/appcompat/view/menu/h00;->y0(Landroid/accounts/IAccountManagerResponse;Ljava/lang/String;Ljava/lang/String;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    return-void
.end method

.method public y()[Landroid/accounts/AuthenticatorDescription;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/h00;->k2(I)[Landroid/accounts/AuthenticatorDescription;

    move-result-object v0
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception v0

    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 v0, 0x0

    return-object v0
.end method

.method public z(Landroid/accounts/Account;)Ljava/util/Map;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/gv0;->c()Landroid/os/IInterface;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/h00;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v1

    invoke-interface {v0, p1, v1}, Landroidx/appcompat/view/menu/h00;->b2(Landroid/accounts/Account;I)Ljava/util/Map;

    move-result-object p1
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    return-object p1
.end method
