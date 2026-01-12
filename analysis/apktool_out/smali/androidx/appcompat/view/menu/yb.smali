.class public final Landroidx/appcompat/view/menu/yb;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/yb$a;
    }
.end annotation


# static fields
.field public static final e:Landroidx/appcompat/view/menu/yb;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/q01;

.field public final b:Ljava/util/List;

.field public final c:Landroidx/appcompat/view/menu/sx;

.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/yb$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/yb$a;-><init>()V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yb$a;->b()Landroidx/appcompat/view/menu/yb;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/yb;->e:Landroidx/appcompat/view/menu/yb;

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/q01;Ljava/util/List;Landroidx/appcompat/view/menu/sx;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/yb;->a:Landroidx/appcompat/view/menu/q01;

    iput-object p2, p0, Landroidx/appcompat/view/menu/yb;->b:Ljava/util/List;

    iput-object p3, p0, Landroidx/appcompat/view/menu/yb;->c:Landroidx/appcompat/view/menu/sx;

    iput-object p4, p0, Landroidx/appcompat/view/menu/yb;->d:Ljava/lang/String;

    return-void
.end method

.method public static e()Landroidx/appcompat/view/menu/yb$a;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/yb$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/yb$a;-><init>()V

    return-object v0
.end method


# virtual methods
.method public a()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yb;->d:Ljava/lang/String;

    return-object v0
.end method

.method public b()Landroidx/appcompat/view/menu/sx;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yb;->c:Landroidx/appcompat/view/menu/sx;

    return-object v0
.end method

.method public c()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yb;->b:Ljava/util/List;

    return-object v0
.end method

.method public d()Landroidx/appcompat/view/menu/q01;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yb;->a:Landroidx/appcompat/view/menu/q01;

    return-object v0
.end method

.method public f()[B
    .locals 1

    invoke-static {p0}, Landroidx/appcompat/view/menu/rk0;->a(Ljava/lang/Object;)[B

    move-result-object v0

    return-object v0
.end method
