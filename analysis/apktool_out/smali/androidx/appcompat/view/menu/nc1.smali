.class public abstract Landroidx/appcompat/view/menu/nc1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/l2$g;

.field public static final b:Landroidx/appcompat/view/menu/l2$g;

.field public static final c:Landroidx/appcompat/view/menu/l2$a;

.field public static final d:Landroidx/appcompat/view/menu/l2$a;

.field public static final e:Lcom/google/android/gms/common/api/Scope;

.field public static final f:Lcom/google/android/gms/common/api/Scope;

.field public static final g:Landroidx/appcompat/view/menu/l2;

.field public static final h:Landroidx/appcompat/view/menu/l2;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Landroidx/appcompat/view/menu/l2$g;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/l2$g;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/nc1;->a:Landroidx/appcompat/view/menu/l2$g;

    new-instance v1, Landroidx/appcompat/view/menu/l2$g;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/l2$g;-><init>()V

    sput-object v1, Landroidx/appcompat/view/menu/nc1;->b:Landroidx/appcompat/view/menu/l2$g;

    new-instance v2, Landroidx/appcompat/view/menu/va1;

    invoke-direct {v2}, Landroidx/appcompat/view/menu/va1;-><init>()V

    sput-object v2, Landroidx/appcompat/view/menu/nc1;->c:Landroidx/appcompat/view/menu/l2$a;

    new-instance v3, Landroidx/appcompat/view/menu/gb1;

    invoke-direct {v3}, Landroidx/appcompat/view/menu/gb1;-><init>()V

    sput-object v3, Landroidx/appcompat/view/menu/nc1;->d:Landroidx/appcompat/view/menu/l2$a;

    new-instance v4, Lcom/google/android/gms/common/api/Scope;

    const-string v5, "profile"

    invoke-direct {v4, v5}, Lcom/google/android/gms/common/api/Scope;-><init>(Ljava/lang/String;)V

    sput-object v4, Landroidx/appcompat/view/menu/nc1;->e:Lcom/google/android/gms/common/api/Scope;

    new-instance v4, Lcom/google/android/gms/common/api/Scope;

    const-string v5, "email"

    invoke-direct {v4, v5}, Lcom/google/android/gms/common/api/Scope;-><init>(Ljava/lang/String;)V

    sput-object v4, Landroidx/appcompat/view/menu/nc1;->f:Lcom/google/android/gms/common/api/Scope;

    new-instance v4, Landroidx/appcompat/view/menu/l2;

    const-string v5, "SignIn.API"

    invoke-direct {v4, v5, v2, v0}, Landroidx/appcompat/view/menu/l2;-><init>(Ljava/lang/String;Landroidx/appcompat/view/menu/l2$a;Landroidx/appcompat/view/menu/l2$g;)V

    sput-object v4, Landroidx/appcompat/view/menu/nc1;->g:Landroidx/appcompat/view/menu/l2;

    new-instance v0, Landroidx/appcompat/view/menu/l2;

    const-string v2, "SignIn.INTERNAL_API"

    invoke-direct {v0, v2, v3, v1}, Landroidx/appcompat/view/menu/l2;-><init>(Ljava/lang/String;Landroidx/appcompat/view/menu/l2$a;Landroidx/appcompat/view/menu/l2$g;)V

    sput-object v0, Landroidx/appcompat/view/menu/nc1;->h:Landroidx/appcompat/view/menu/l2;

    return-void
.end method
